#!/bin/sh

for stuff in $(cat loco)
do
	echo -ne $stuff
	sleep 0
done

bash $0