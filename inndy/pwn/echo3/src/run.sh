#!/bin/bash

cd /home/ctf
exec sudo -Hu ctf timeout -sSIGKILL 99 ./echo3
