################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../cfgparse.c \
../fcrypt.c \
../fspathtools.c \
../ftpconst.c \
../ftpserv.c \
../main.c 

C_DEPS += \
./cfgparse.d \
./fcrypt.d \
./fspathtools.d \
./ftpconst.d \
./ftpserv.d \
./main.d 

OBJS += \
./cfgparse.o \
./fcrypt.o \
./fspathtools.o \
./ftpconst.o \
./ftpserv.o \
./main.o 

# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -O3 -pedantic -Wall -Wextra -c -fmessage-length=0 -v -fPIC -fstack-protector-all -Wformat=2 -Wformat-security -Wstrict-overflow -fPIE -pthread -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean--2e-

clean--2e-:
	-$(RM) ./cfgparse.d ./cfgparse.o ./fcrypt.d ./fcrypt.o ./fspathtools.d ./fspathtools.o ./ftpconst.d ./ftpconst.o ./ftpserv.d ./ftpserv.o ./main.d ./main.o

.PHONY: clean--2e-

