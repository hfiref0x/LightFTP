################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# CC = gcc
# CFLAGS = -fPIC -fprofile-arcs -ftest-coverage

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: fftp

# Tool invocations
fftp: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) $(CFLAGS) -pthread -fPIC -fprofile-arcs -ftest-coverage \
	-o "fftp" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

coverage: 
	gcov $(C_SRCS)

lcov-report:coverage
	mkdir lcov-report
	lcov --capture --directory . --output-file lcov-report/coverage.info
	genhtml lcov-report/coverage.info --output-directory lcov-report

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) fftp
	-@echo ' '

.PHONY: all clean dependents

-include ../makefile.targets
