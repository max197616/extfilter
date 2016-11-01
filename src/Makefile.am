AM_CPPFLAGS = -I$(top_srcdir)/$(PPP_HEADER) -I$(top_srcdir)/nDPI/src/include -I$(DPDK_INCLUDE)
LDADD =-lpcap -L$(top_srcdir)/$(PPP_LIB) -lPcap++ -lPacket++ -lCommon++ \
-L $(DPDK_LIB)  -lrt -lm -ldl $(top_srcdir)/nDPI/src/lib/.libs/libndpi.a

bin_PROGRAMS = extFilter

extFilter_LDFLAGS = -Wl,--whole-archive -lrte_pmd_bond -lrte_pmd_vmxnet3_uio -lrte_pmd_virtio -lrte_pmd_enic -lrte_pmd_i40e -lrte_pmd_fm10k -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_af_packet -lethdev -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring -lrte_kvargs -lrte_hash -lrte_cmdline -Wl,--no-whole-archive

extFilter_SOURCES = main.cpp worker.cpp AhoCorasickPlus.cpp ahocorasick.cpp node.cpp patricia.c patr.cpp qdpi.cpp sender.cpp sendertask.cpp statistictask.cpp reloadtask.cpp flow.cpp reader.cpp

