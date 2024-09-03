import os

from dotenv import load_dotenv
from omegaconf import OmegaConf, DictConfig

load_dotenv()
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(PROJECT_ROOT, 'config.yml')

CONFIG = OmegaConf.to_container(OmegaConf.load(CONFIG_PATH), resolve=True)
