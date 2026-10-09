"""Onboard a new Windows product for patch management.

Pipeline: scrape installers -> download -> pick VM by arch -> snapshot ->
silent install (with fallbacks) -> snapshot -> diff -> report.
"""
__version__ = "0.1.0"
