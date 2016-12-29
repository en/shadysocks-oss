#!/bin/bash

testdata=("Denmark’s a prison.",
"Then is the world one.",
"A goodly one, in which there are many confines, wards, and dungeons, Denmark being one o' th' worst.",
"We think not so, my lord.",
"Why, then, ’tis none to you, for there is nothing either good or bad, but thinking makes it so. To me it is a prison.",
"Why then, your ambition makes it one. 'Tis too narrow for your mind.",
"O God, I could be bounded in a nutshell and count myself a king of infinite space, were it not that I have bad dreams.")

func_env() {
	# TCP echo server
	ncat -e /bin/cat -k -l 8888 &
	# UDP echo server
	ncat -e /bin/cat -k -u -l 9999 &
	pnode 2>&1 > /dev/null &
	rnode 2>&1 > /dev/null &
	# TCP client
	coproc tc { SOCKS_AUTOADD_LANROUTES=no socksify ncat 127.0.0.1 8888; }
	# UDP client
	coproc uc { SOCKS_AUTOADD_LANROUTES=no socksify ncat -u 127.0.0.1 9999; }
}

func_report() {
	ret=$1

	case $ret in
		0)
			echo "$protocal$ota test succeeded!"
			;;
		*)
			echo "$protocal$ota test failed!"
			;;
	esac

	trap 'jobs -p | xargs kill' EXIT
	exit $ret
}

func_test() {
	in=$1
	out=$2
	data=$3

	printf >&$in '%s\n' "$data"
	IFS= read -r -u$out line
	if [ "$line" != "$data" ]; then
		func_report $protocal 1
	fi
}

ota=
sed -i 's/^\(one_time_auth\s*=\s*\).*$/\1false/' config.toml

func_env
for i in ${!testdata[*]}; do
	protocal="TCP"
	func_test ${tc[1]} ${tc[0]} ${testdata[$i]}

	protocal="UDP"
	func_test ${uc[1]} ${uc[0]} ${testdata[$i]}
done
killall -wq ncat rnode pnode

ota=" OTA"
sed -i 's/^\(one_time_auth\s*=\s*\).*$/\1true/' config.toml

func_env
for i in ${!testdata[*]}; do
	protocal="TCP"
	func_test ${tc[1]} ${tc[0]} ${testdata[$i]}

	protocal="UDP"
	func_test ${uc[1]} ${uc[0]} ${testdata[$i]}
done

ota=
sed -i 's/^\(one_time_auth\s*=\s*\).*$/\1false/' config.toml
protocal="ALL"
func_report 0
