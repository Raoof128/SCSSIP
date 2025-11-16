"""
Advanced Threat Hunting Platform with Behavioral Analytics

A production-ready threat hunting platform that combines behavioral analytics,
machine learning, and automated investigation orchestration to detect advanced
persistent threats (APTs) with high accuracy and low false positive rates.
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from loguru import logger
import sys

# Configure default logging
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO"
)
