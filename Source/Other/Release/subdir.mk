################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../cfgparse.c \
../ftpserv.c \
../main.c 

OBJS += \
./cfgparse.o \
./ftpserv.o \
./main.o 

C_DEPS += \
./cfgparse.d \
./ftpserv.d \
./main.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -std=c99 -O3 -Wall -Wextra -c -fmessage-length=0 -Wno-unused-parameter -Wno-unused-result -fno-ident -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


