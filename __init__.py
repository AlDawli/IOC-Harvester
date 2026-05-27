"""
IOC Harvester
=============
Threat intelligence aggregator that pulls Indicators of Compromise
from Abuse.ch, AlienVault OTX, and ThreatFox, then exports them
to CSV, Sigma detection rules, and firewall blocklists.
"""

__version__ = "1.0.0"
__author__ = "IOC Harvester"
__license__ = "MIT"

from ioc_harvester.harvester import harvest, run_and_export
from ioc_harvester.models import IOC, IOCType, ThreatCategory

__all__ = ["harvest", "run_and_export", "IOC", "IOCType", "ThreatCategory"]
