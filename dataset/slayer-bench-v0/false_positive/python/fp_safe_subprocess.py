import subprocess

def convert_image(input_path: str, output_path: str) -> None:
    subprocess.run(['convert', input_path, '-resize', '800x600', output_path], check=True)

def list_files(directory: str) -> bytes:
    result = subprocess.run(['ls', '-la', directory], capture_output=True, shell=False)
    return result.stdout
