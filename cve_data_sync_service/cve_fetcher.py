import asyncio
import logging
import os

import aiohttp

from cve_data_sync_service import SYNC_CONFIG

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


async def run_command(command, cwd=None):
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )

    async for line in process.stdout:
        logging.info(line.decode('utf-8').strip())

    async for line in process.stderr:
        logging.error(line.decode('utf-8').strip())

    await process.wait()


async def is_git_installed():
    try:
        await run_command(["git", "--version"])
        return True
    except (FileNotFoundError, CalledProcessError):
        return False


async def initial_clone():
    if not await is_git_installed():
        logging.error("Git is not installed. Please install Git to proceed.")
        return

    repo_url = SYNC_CONFIG['repo_url']
    clone_dir = SYNC_CONFIG['data_dir']

    if not os.path.exists(clone_dir):
        try:
            logging.info(f"Cloning repository into {clone_dir}...")
            await run_command(["git", "clone", repo_url, "--depth=1", clone_dir])
            logging.info(f"Repository cloned successfully into {clone_dir}")
        except asyncio.SubprocessError as e:
            logging.error(f"Error cloning repository: {e}")
    else:
        logging.info(f"Repository already exists in {clone_dir}, pulling latest changes.")
        try:
            await run_command(["git", "pull"], cwd=clone_dir)
            logging.info("Repository updated successfully.")
        except asyncio.SubprocessError as e:
            logging.error(f"Error updating repository: {e}")


import aioschedule as schedule


async def fetch_cve_updates():
    url = "https://api.github.com/repos/CVEProject/cvelistV5/commits"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                updates = await response.json()
                return updates
            else:
                print(f"Failed to fetch CVE updates: {response.status}")
                return None


async def update_cve_data():
    updates = await fetch_cve_updates()
    if updates:

        print(f"Fetched {len(updates)} updates.")

    else:
        print("No updates fetched.")


async def schedule_cve_updates(interval_hours):
    await update_cve_data()
    schedule.every(interval_hours).hours.do(update_cve_data)
    while True:
        await schedule.run_pending()
        await asyncio.sleep(1)


interval_hours = SYNC_CONFIG['interval_update']
asyncio.run(schedule_cve_updates(interval_hours))
