import asyncio
import logging
import os
from subprocess import CalledProcessError

import aiohttp

from cve_data_sync_service import SYNC_CONFIG
from cve_data_sync_service.delta_log import get_last_fetch_time, get_and_process_updates

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


async def fetch_cve_updates():
    clone_dir = SYNC_CONFIG['data_dir']

    if not os.path.exists(clone_dir):
        logging.error(f"Directory {clone_dir} does not exist. Cannot pull updates.")
        return
    try:
        logging.info(f"Pulling latest changes in {clone_dir}...")
        await run_command(["git", "-C", clone_dir, "pull", "origin", "main"])
        logging.info(f"Repository updated successfully in {clone_dir}")
    except CalledProcessError as e:
        logging.error(f"Error pulling repository: {e}")


async def update_cve_data():
    last_fetch_time = await get_last_fetch_time()
    await fetch_cve_updates()
    await get_and_process_updates(last_fetch_time)


async def schedule_cve_updates(interval_hours):
    SECONDS_IN_HOUR = 3600
    interval = interval_hours * SECONDS_IN_HOUR
    while True:
        await asyncio.sleep(interval)
        await update_cve_data()


async def cve_data_fetch():
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
        except CalledProcessError as e:
            logging.error(f"Error cloning repository: {e}")

    interval_hours = SYNC_CONFIG['update_interval_hours']
    logging.info(f"Repository is pulled to {clone_dir}, schedule regular fetch every {interval_hours} hours.")
    try:
        await schedule_cve_updates(interval_hours)
    except CalledProcessError as e:
        logging.error(f"Error updating repository: {e}")


asyncio.run(cve_data_fetch())

if __name__ == "__main__":
    asyncio.run(cve_data_fetch())
