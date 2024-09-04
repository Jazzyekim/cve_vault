import asyncio

from cve_data_sync_service import SYNC_CONFIG
from cve_fetcher import initial_clone, schedule_cve_updates

asyncio.run(initial_clone())

asyncio.run(schedule_cve_updates(1))
