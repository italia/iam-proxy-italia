from enum import Enum


class KeyUsage(str, Enum):
    signature = "sig"
    encryption = "enc"
