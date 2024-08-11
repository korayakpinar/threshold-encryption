import asyncio
import subprocess
import time
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
    testsize = 60
    wait = 0
    if len(sys.argv) == 2:
        testsize = int(sys.argv[1])
    if len(sys.argv) == 3:
        wait = float(sys.argv[2])

    tasks = [run_command(i, wait) for i in range(testsize)]
    t = time.time()
    results = await asyncio.gather(*tasks)
    
    q = sum(1 for result in results if result == 0)
    
    print(f"Number of successful runs: {q} in {time.time() - t}s")

if __name__ == "__main__":
    asyncio.run(main())
