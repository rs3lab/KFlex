#!/bin/bash

#!/bin/bash
# - disables the Linux realtime throttling which ensures that realtime processes cannot starve the CPUS.
# - disables the Linux watchdog timer which is used to detect and recover from software faults.
# - disables the debugging feature for catching hardware hangings.
# - sets the default CPU affinity of 0b11 (3), which means that only CPU 0 and 1 handle interrupts.
# - moves all interrupts off cpus specified below starting at 2 and above.

GEN_UNISOLATE=true

cpus="0"

if [ $GEN_UNISOLATE = true ]; then
  if [ ! -f unisolate.sh ]; then
    echo "#!/bin/bash" > unisolate.sh
    p0=`cat /proc/sys/kernel/sched_rt_runtime_us`
    p1=`cat /proc/sys/kernel/watchdog`
    p2=`cat /proc/sys/kernel/nmi_watchdog`
    p3=`cat /proc/irq/default_smp_affinity`
    echo "echo ${p0} > /proc/sys/kernel/sched_rt_runtime_us" >> unisolate.sh
    echo "echo ${p1} > /proc/sys/kernel/watchdog" >> unisolate.sh
    echo "echo ${p2} > /proc/sys/kernel/nmi_watchdog" >> unisolate.sh
    echo "echo ${p3} > /proc/irq/default_smp_affinity" >> unisolate.sh

    for irq in `ls -d /proc/irq/*/ | cut -d/ -f 4`;
    do
      val=`cat /proc/irq/$irq/smp_affinity`
      echo "echo ${val} > /proc/irq/$irq/smp_affinity 2>/dev/null" >> unisolate.sh
    done

    for cpu in $cpus
    do
      word=`cat /sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor`
      echo "echo \"${word}\" > /sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor" >> unisolate.sh
      val=`cat /sys/devices/system/machinecheck/machinecheck$cpu/check_interval`
      echo "echo ${val} > /sys/devices/system/machinecheck/machinecheck$cpu/check_interval" >> unisolate.sh
    done

    chmod +x unisolate.sh
  else
    echo "unisolate.sh already exists, are cores already isolated? Caution: don't create unisolate.sh while cores are currently isolated"
    exit 1
  fi
fi

echo -1 > /proc/sys/kernel/sched_rt_runtime_us
echo 0 > /proc/sys/kernel/watchdog
echo 0 > /proc/sys/kernel/nmi_watchdog
echo 3 > /proc/irq/default_smp_affinity

for irq in `ls -d /proc/irq/*/ | cut -d/ -f 4`; do echo 1 > /proc/irq/$irq/smp_affinity 2>/dev/null; done
for irq in `ls -d /proc/irq/*/ | cut -d/ -f 4`; do echo -n "$irq  ";  cat /proc/irq/$irq/smp_affinity_list; done

for cpu in $cpus
do
  echo "performance" > /sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor
  echo 0 > /sys/devices/system/machinecheck/machinecheck$cpu/check_interval
done
