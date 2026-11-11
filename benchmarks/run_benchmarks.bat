@echo off
setlocal
cd /d "%~dp0\.."
if not exist data mkdir data

echo Running Q-SHIELD cryptographic benchmarks...
python -m benchmarks.bench_pq_vs_classic --iterations 20 --output data/benchmarks.json
if errorlevel 1 (
    echo Benchmark generation failed. Check the active virtual environment
    echo and verify liboqs-python exposes ML-KEM-768 and ML-DSA-65.
    exit /b 1
)

echo.
echo Created data\benchmarks.json
echo Refresh the Q-SHIELD dashboard to view measured results.
echo Add the measured file with: git add data/benchmarks.json
endlocal
