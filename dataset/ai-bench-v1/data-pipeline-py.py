import json
import sqlite3
import subprocess
import sys
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests
from datetime import datetime
import argparse

# I'm using logging now because Claude suggested it was important lol
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON file. Super simple but it works!!"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logger.info(f"✅ Loaded config from {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"❌ Config file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"❌ Invalid JSON in config: {e}")
        sys.exit(1)


def fetch_from_api(api_url: str, api_key: Optional[str] = None, timeout: int = 30) -> List[Dict]:
    """Fetch data from API. Using requests because it's literally the easiest."""
    headers = {}
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    
    try:
        logger.info(f"🌐 Fetching from {api_url}...")
        response = requests.get(api_url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        # Handle both list and paginated responses
        data = response.json()
        if isinstance(data, dict) and 'results' in data:
            data = data['results']
        elif isinstance(data, dict) and 'data' in data:
            data = data['data']
        
        if not isinstance(data, list):
            data = [data]
        
        logger.info(f"✅ Fetched {len(data)} records")
        return data
    except requests.RequestException as e:
        logger.error(f"❌ API request failed: {e}")
        sys.exit(1)


def apply_filters(data: List[Dict], filters: Optional[Dict[str, Any]]) -> List[Dict]:
    """Apply user-provided filters to dataset. This is where Claude said to use filter()."""
    if not filters:
        return data
    
    filtered = data
    for key, value in filters.items():
        if isinstance(value, dict):
            op = value.get('operator', 'eq')
            val = value.get('value')
            
            if op == 'eq':
                filtered = [r for r in filtered if r.get(key) == val]
            elif op == 'gt':
                filtered = [r for r in filtered if r.get(key, 0) > val]
            elif op == 'lt':
                filtered = [r for r in filtered if r.get(key, 0) < val]
            elif op == 'contains':
                filtered = [r for r in filtered if val in str(r.get(key, ''))]
            elif op == 'in':
                filtered = [r for r in filtered if r.get(key) in val]
        else:
            filtered = [r for r in filtered if r.get(key) == value]
    
    logger.info(f"📊 Applied filters: {len(data)} → {len(filtered)} records")
    return filtered


def transform_with_subprocess(data: List[Dict], transform_cmd: str, data_field: str = 'content') -> List[Dict]:
    """Run external transformation tool via subprocess. Very cool that we can do this!"""
    transformed = []
    
    for i, record in enumerate(data):
        try:
            # Prepare input for subprocess
            input_text = record.get(data_field, '')
            
            # Run transformation command
            logger.info(f"🔄 Processing record {i+1}/{len(data)}...")
            result = subprocess.run(
                transform_cmd,
                input=input_text.encode('utf-8'),
                capture_output=True,
                timeout=60,
                shell=False
            )
            
            if result.returncode != 0:
                logger.warning(f"⚠️  Subprocess returned {result.returncode}: {result.stderr.decode()}")
                transformed.append(record)
            else:
                record['transformed_content'] = result.stdout.decode('utf-8').strip()
                transformed.append(record)
        except subprocess.TimeoutExpired:
            logger.warning(f"⚠️  Subprocess timeout for record {i+1}")
            transformed.append(record)
        except Exception as e:
            logger.warning(f"⚠️  Subprocess error: {e}")
            transformed.append(record)
    
    logger.info(f"✅ Transformation complete")
    return transformed


def initialize_database(db_path: str, schema: Optional[List[str]] = None) -> sqlite3.Connection:
    """Initialize SQLite database with schema."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    if schema:
        for sql in schema:
            cursor.execute(sql)
            logger.info(f"✅ Created table")
    else:
        # Default schema if none provided
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT,
                data TEXT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(source_id)
            )
        ''')
    
    conn.commit()
    return conn


def store_in_database(
    conn: sqlite3.Connection,
    data: List[Dict],
    table_name: str = 'records',
    id_field: str = 'id'
) -> int:
    """Store processed data in SQLite database."""
    cursor = conn.cursor()
    stored_count = 0
    
    for record in data:
        try:
            # Convert record to JSON string for storage
            record_json = json.dumps(record)
            source_id = str(record.get(id_field, ''))
            
            cursor.execute(f'''
                INSERT OR REPLACE INTO {table_name} 
                (source_id, data, processed_at) 
                VALUES (?, ?, ?)
            ''', (source_id, record_json, datetime.now().isoformat()))
            
            stored_count += 1
        except Exception as e:
            logger.warning(f"⚠️  Failed to store record: {e}")
    
    conn.commit()
    logger.info(f"💾 Stored {stored_count}/{len(data)} records in {table_name}")
    return stored_count


def main():
    """Main pipeline orchestration. This is my masterpiece!"""
    parser = argparse.ArgumentParser(description='Data Pipeline ETL')
    parser.add_argument('--config', default='pipeline_config.json', help='Config file path')
    parser.add_argument('--db', default='pipeline.db', help='SQLite database path')
    parser.add_argument('--dry-run', action='store_true', help='Dry run without DB writes')
    args = parser.parse_args()
    
    logger.info("=" * 60)
    logger.info("🚀 DATA PIPELINE STARTED")
    logger.info("=" * 60)
    
    # Load configuration
    config = load_config(args.config)
    
    # Fetch data from API
    api_url = config.get('api_url')
    api_key = config.get('api_key')
    if not api_url:
        logger.error("❌ api_url not found in config")
        sys.exit(1)
    
    data = fetch_from_api(api_url, api_key)
    
    # Apply filters
    filters = config.get('filters')
    data = apply_filters(data, filters)
    
    # Run transformations if specified
    if config.get('transform_command'):
        data = transform_with_subprocess(
            data,
            config['transform_command'],
            config.get('transform_field', 'content')
        )
    
    if args.dry_run:
        logger.info("🧪 DRY RUN - no database writes")
        logger.info(f"Would store {len(data)} records")
        return
    
    # Initialize database and store results
    db_conn = initialize_database(args.db, config.get('schema'))
    store_in_database(
        db_conn,
        data,
        config.get('table_name', 'records'),
        config.get('id_field', 'id')
    )
    db_conn.close()
    
    logger.info("=" * 60)
    logger.info(f"✅ PIPELINE COMPLETE - {len(data)} records processed")
    logger.info("=" * 60)


if __name__ == '__main__':
    main()