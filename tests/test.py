import asyncio
import subprocess
import sys

async def run_command(i, wait):
    await asyncio.sleep(wait * i)
    print(f"Starting task {i}")
    process = await asyncio.create_subprocess_exec(
        './main',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    returncode = await process.wait()
    print(f"Task {i} completed with return code {returncode}")
    return returncode

async def main():
    wait = 0
    if len(sys.argv) == 2:
        wait = float(sys.argv[1])
    tasks = [run_command(i, wait) for i in range(60)]
    results = await asyncio.gather(*tasks)
    
    q = sum(1 for result in results if result == 0)
    
    print(f"Number of successful runs: {q}")

if __name__ == "__main__":
    asyncio.run(main())
