all:
	gcc cipher.c main.c mecha_emu.c util.c -o kelf-tool
clean:
	rm kelf-tool