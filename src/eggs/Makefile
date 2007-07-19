SUBDIRS = bit-cat  crc16  raw-sockets

all:
	@for T in $(SUBDIRS); do make -C $$T $@; done

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@for T in $(SUBDIRS); do make -C $$T $@; done

