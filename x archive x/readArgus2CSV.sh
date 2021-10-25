echo "reading argus file into .csv"
ra -r teste.argus -c ',' -s saddr sport daddr dport proto \
state dur sbytes dbytes sttl dttl sloss dloss service sload dload spkts dpkts \
swin dwin stcpb dtcpb smeansz dmeansz \
sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat \
trans min max sum -M dsrs=+time,+flow,+metric,+agr,+jitter > myArgus.csv
