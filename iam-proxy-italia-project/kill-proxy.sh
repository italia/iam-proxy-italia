#!/bin/bash

ps ax | grep uwsgi | grep :10000 | awk -F' ' {'print $1'} | xargs kill -kill
