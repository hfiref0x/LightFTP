################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../cfgparse.c \
../ftpconst.c \
../ftpserv.c \
../main.c \
../x_malloc.c 

OBJS += \
./cfgparse.o \
./ftpconst.o \
./ftpserv.o \
./main.o \
./x_malloc.o 

C_DEPS += \
./cfgparse.d \
./ftpconst.d \
./ftpserv.d \
./main.d \
./x_malloc.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -std=c99 -O3 -Wall -Wextra -c -fmessage-length=0 -Wno-unused-parameter -Wno-unused-result -fno-ident -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


