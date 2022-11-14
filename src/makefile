all: fntf_detect
	rm -r mount_point/ || true
	mkdir mount_point
	mount --bind $(ARGS) ./mount_point
	./fntf_detect $(ARGS)

fntf_detect: fntf_detect.c
	gcc fntf_detect.c -o fntf_detect
