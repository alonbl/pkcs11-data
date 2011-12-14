#!/bin/sh

if [ "x$1" = "x-t" ]; then
	type="$2"
	shift 2
fi

echo -n "$1" >&2

case "$type" in
	text)
		read f
		echo $f
	;;
	password)
		stty -echo
		read f
		stty echo
		echo >&2
		echo $f
	;;
	none|*)
		:
	;;
esac

