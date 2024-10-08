#!/bin/bash 

# Make sure only root can run our script

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

### Functions
#This function will count memory statistic for passed PID
get_process_mem ()
{
    PID=$1
#we need to check if 2 files exist
    if [ -f /proc/$PID/status ];
    then
	if [ -f /proc/$PID/smaps ];
	then
#here we count memory usage, Pss, Private and Shared = Pss-Private
	    Pss=`cat /proc/$PID/smaps | grep -e "^Pss:" | awk '{print $2}'| paste -sd+ | bc `
	    Private=`cat /proc/$PID/smaps | grep -e "^Private" | awk '{print $2}'| paste -sd+ | bc `
#we need to be sure that we count Pss and Private memory, to avoid errors
	    if [ x"$Pss" != "x" -o x"$Private" != "x" ];
	    then

		let Shared=${Pss}-${Private}
		Name=`cat /proc/$PID/status | grep -e "^Name:" |cut -d':' -f2`
#we keep all results in bytes
		let Shared=${Shared}*1024
		let Private=${Private}*1024
		let Sum=${Shared}+${Private}

		echo -e "$Private + $Shared = $Sum \t $Name"
	    fi
	fi
    fi
}

#this function make conversion from bytes to Kb or Mb or Gb
convert()
{
    value=$1
    power=0
#if value 0, we make it like 0.00
    if [ "$value" = "0" ];
    then
	value="0.00"
    fi

#We make conversion till value bigger than 1024, and if yes we divide by 1024
    while [ $(echo "${value} > 1024"|bc) -eq 1 ]
    do
	value=$(echo "scale=2;${value}/1024" |bc)
	let power=$power+1
    done

#this part get b,kb,mb or gb according to number of divisions
    case $power in
	0) reg=b;;
	1) reg=kb;;
	2) reg=mb;;
	3) reg=gb;;
    esac

    echo -n "${value} ${reg} "
}


start() {
#to ensure that temp files not exist
    [[ -f /tmp/cli_memory_report/res$$ ]] && rm -f /tmp/cli_memory_report/res$$
    [[ -f /tmp/cli_memory_report/res2$$ ]] && rm -f /tmp/cli_memory_report/res2$$
    [[ -f /tmp/cli_memory_report/res3$$ ]] && rm -f /tmp/cli_memory_report/res3$$
    [[ -f /tmp/cli_memory_report/list$$ ]] && rm -f /tmp/cli_memory_report/list$$ 

    pids=$(ps --ppid=$1 | grep -v $$ | grep -v PID  | awk '{ print $1 }' )
    echo "pids $pids" >> /tmp/cli_memory_report/list$$
#if argument passed script will show statistic only for that pid, of not – we list all processes in /proc/ #and get statistic for all of them, all result we store in file /tmp/cli_memory_report/res
    #if [ $# -eq 0 ]
    #then
#	pids=`ls /proc | grep -e [0-9] | grep -v [A-Za-z] `
	for i in $pids
	do
	    get_process_mem $i >> /tmp/cli_memory_report/res$$
	done
    #else
#	get_process_mem $1>> /tmp/cli_memory_report/res
#    fi

#This will sort result by memory usage
    cat /tmp/cli_memory_report/res$$ | sort -gr -k 5 > /tmp/cli_memory_report/res2$$

#this part will get uniq names from process list, and we will add all lines with same process list
#we will count nomber of processes with same name, so if more that 1 process where will be
# process(2) in output
    for Name in `cat /tmp/cli_memory_report/res2$$ | awk '{print $6}' | sort | uniq`
    do
	count=`cat /tmp/cli_memory_report/res2$$ | awk -v src=$Name '{if ($6==src) {print $6}}'|wc -l| awk '{print $1}'`
	if [ $count = "1" ];
	then
	    count=""
	else
	    count="(${count})"
	fi

	VmSizeKB=`cat /tmp/cli_memory_report/res2$$ | awk -v src=$Name '{if ($6==src) {print $1}}' | paste -sd+ | bc`
	VmRssKB=`cat /tmp/cli_memory_report/res2$$ | awk -v src=$Name '{if ($6==src) {print $3}}' | paste -sd+ | bc`
	total=`cat /tmp/cli_memory_report/res2$$ | awk '{print $5}' | paste -sd+ | bc`
	Sum=`echo "${VmRssKB}+${VmSizeKB}"|bc`
#all result stored in /tmp/cli_memory_report/res3 file
	echo -e "$VmSizeKB + $VmRssKB = $Sum \t ${Name}${count}" >>/tmp/cli_memory_report/res3$$
    done

#this make sort once more.
    cat /tmp/cli_memory_report/res3$$ | sort -gr -k 5 | uniq > /tmp/cli_memory_report/res$$

#now we print result , first header
#    echo -e "Private \t + \t Shared \t = \t RAM used \t Program"
#after we read line by line of temp file
    while read line
    do
	echo $line | while read a b c d e f
	do
#we print all processes if Ram used if not 0
	    if [ $e != "0" ]; then
#here we use function that make conversion
		echo -en "`convert $a` \t $b \t `convert $c` \t $d \t `convert $e` \t $f"
		echo ""
	    fi
	done
    done < /tmp/cli_memory_report/res$$ 
#this part print footer, with counted Ram usage echo "--------------------------------------------------------" echo -e "\t\t\t\t\t\t `convert $total`" echo "========================================================" 
# we clean temporary file 



}

    echo " start $(date)" 
    start $@ 


for i in `seq 1 100`;
        do
                sleep 1 
                start $@ 
        done    

# removing temps files 

[[ -f /tmp/cli_memory_report/res$$  ]] && rm -f /tmp/cli_memory_report/res$$ 
[[ -f /tmp/cli_memory_report/res2$$ ]] && rm -f /tmp/cli_memory_report/res2$$ 
[[ -f /tmp/cli_memory_report/res3$$ ]] && rm -f /tmp/cli_memory_report/res3$$ 
[[ -f /tmp/cli_memory_report/list$$ ]] && rm -f /tmp/cli_memory_report/list$$ 
