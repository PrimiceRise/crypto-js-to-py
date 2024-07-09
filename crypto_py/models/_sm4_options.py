#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
@Project ：DP 
@File    ：_sm4_options.py
@IDE     ：PyCharm 
@Author  ：Primice
@Date    ：2024/7/5 21:22 
'''

from pydantic import BaseModel,Field
from typing import Callable,Optional

class SM4Options(BaseModel):
    mode: int
    padding: Callable
    iv: Optional[bytes|str] = Field(default=None)