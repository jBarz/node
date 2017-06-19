#!/sh

curr=0
file=0
count=0

$(dirname $0)/cleanup.sh ../

#loop to find and remove any potential propositional arguments that could
#prevent the pre-processing step from producing a .u header file
for var in $@
do
    match=$(echo $var | grep "\-c")
    match2=$(echo $var | grep "\-MF")
    if [[ ! -z $match ]]
    then
        deleted[count]=$var
        count=$((count+1))
        continue
    elif [[ ! -z $match2 ]]
    then
        file=1
        deleted[count]=$var
        count=$((count+1))
        continue
    else
        if [ $file = 0 ]
        then
            new[curr]=$var
            curr=$((curr+1))
        else
            file=0
            deleted[count]=$var
            count=$((count+1))
        fi
    fi
done

# first=$(echo $@ | sed -E 's/(.+)-c (.+)/\1\2/')
# deleted[0]="-c"
# new=$(echo $first | sed -E 's/(.+)-MF [A-Z0-9a-z/\._-]*(.+)/\1\2/')
# deleted[1]=$(echo $first | sed -E 's/.+(-MF [A-Z0-9a-z/\._-]*).+/\1/')

#iterate over each .c, .cc, .cpp file that's been given and call the convereter
CFLAG=0
count=0
compiled=0
for var in ${new[*]}
do
    fileend=$(echo $var | sed -E 's/.+(\.[a-zA-Z0-9]+)/\1/')
    if [ $fileend = ".cc" ] || [ $fileend = ".cpp" ] || [ $fileend = ".c" ] || [ $fileend = ".cxx" ]
    then
        if [ $compiled = 0 ]
        then
            if [ $fileend = ".c" ]
            then
                compiled=1
                CFLAG=1
                njsc -E ${new[*]} > garbage.c
            else
                compiled=1
                njsc++ -E ${new[*]} > garbage.c
            fi
        fi
        HEADER=$(echo $var | sed -E 's/.*\/([A-Za-z0-9_\-\.]+)\.[a-zA-Z0-9]+/\1.u/')
        TEMP=$(echo $var | sed -E 's/(.+)\.([A-Z0-9a-z]+)/\1_temp.\2/')
        python $(dirname $0)/ebcdic2ascii.py -H $HEADER $var $TEMP
        COMPILE[count]=$TEMP
        count=$((count+1))
    else
        COMPILE[count]=$var
        count=$((count+1))
    fi
done

# compile using the temp file that has been converted into ascii
if [ $CFLAG = 1 ]
then
    njsc ${COMPILE[*]} ${deleted[*]}
else
    njsc++ ${COMPILE[*]} ${deleted[*]}
fi

# get rid of all files created
$(dirname $0)/cleanup.sh ../
