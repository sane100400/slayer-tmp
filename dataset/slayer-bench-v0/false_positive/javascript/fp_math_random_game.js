function spawnEnemy(level) {
  const x = Math.random() * 800;
  const y = Math.random() * 600;
  const speed = Math.random() * level * 2;
  return { x, y, speed };
}

function getRandomColor() {
  const r = Math.floor(Math.random() * 256);
  const g = Math.floor(Math.random() * 256);
  const b = Math.floor(Math.random() * 256);
  return `rgb(${r},${g},${b})`;
}
