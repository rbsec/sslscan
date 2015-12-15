LFLAGS=/nologo /dynamicbase /highentropyva /nxcompat /opt:ref /subsystem:console /ltcg
CFLAGS=/nologo /GL /GS /Gs0 /Gw /MT /Ox -DVERSION="\"1.9.8 Windows 64-bit (VS)\""

all: sslscan.exe

sslscan.obj: sslscan.c
	cl.exe $(CFLAGS) /I $(OPENSSL_PATH)/include /c sslscan.c

sslscan.exe: sslscan.obj
	link.exe $(LFLAGS) /out:sslscan.exe sslscan.obj $(OPENSSL_PATH)/out32/libeay32.lib $(OPENSSL_PATH)/out32/ssleay32.lib advapi32.lib gdi32.lib user32.lib ws2_32.lib

clean:
	del sslscan.obj sslscan.exe

rebuild: clean all
