################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/gcm.cpp \
../src/gcm_test.cpp 

LD_SRCS += \
../src/lscript.ld 

OBJS += \
./src/gcm.o \
./src/gcm_test.o 

CPP_DEPS += \
./src/gcm.d \
./src/gcm_test.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp
	@echo Building file: $<
	@echo Invoking: ARM g++ compiler
	arm-xilinx-eabi-g++ -Wall -O0 -g3 -c -fmessage-length=0 -I../../GCM_bsp/ps7_cortexa9_0/include -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo Finished building: $<
	@echo ' '


