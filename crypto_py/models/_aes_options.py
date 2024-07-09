# -*- coding: utf-8 -*-
# -------------------------------

# @IDE：PyCharm
# @Python：3.1x
# @Project：DP

# -------------------------------

# @fileName：_aes_options.py
# @createTime：2024/7/3 9:52
# @author：Primice

# -------------------------------
from pydantic import BaseModel,Field
from typing import Callable,Optional


class AESOption(BaseModel):
    mode: int
    padding: Callable
    iv: Optional[bytes] = Field(default=None)