if [ $# -eq 1 ]; then
    ko_name=$1
    dev_name=$ko_name
elif [ $# -eq 2 ]; then
    ko_name=$1
    dev_name=$2
else
    echo "Usage: ./debug.sh ko_name (dev_name)"
    exit
fi
echo "Notice: plz close kptr_restrict first"
echo ""
tail /proc/kallsyms
echo "------------------------------------------------------------"
head -n 3 /proc/kallsyms
echo "------------------------------------------------------------"
text=$(grep 0 /sys/module/$dev_name/sections/.text)
bss=$(grep 0 /sys/module/$dev_name/sections/.bss)
data=$(grep 0 /sys/module/$dev_name/sections/.data)
add="add-symbol-file ./"$ko_name".ko "$text" -s .data "$data" -s .bss "$bss
echo $add
