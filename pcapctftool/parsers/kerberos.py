# coding: utf-8

from pyshark.packet.layers.base import BaseLayer

from pcapctftool import logger
from pcapctftool.session import Session


def analyse(session: Session, layer: BaseLayer) -> bool:
    logger.debug("Kerberos analysis...")

    return False
