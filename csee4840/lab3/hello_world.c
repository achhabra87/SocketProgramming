#include <io.h>
#include <system.h>
#include <stdio.h>

#define IOWR_LED_DATA(base, offset, data) \
  IOWR_16DIRECT(base, (offset) * 2, data) 
#define IORD_LED_DATA(base, offset) \
  IORD_16DIRECT(base, (offset) * 2)
#define IOWR_LED_SPEED(base, data) \
  IOWR_16DIRECT(base + 32, 0, data)

int main()
{
  int i;
  printf("Hello Michael\n");

  IOWR_LED_SPEED(LEDS_BASE, 0x0040);
  
  for (i = 0 ; i < 8 ; i++) {
    IOWR_LED_DATA(LEDS_BASE, i, 3 << (i * 2));
    printf("writing %x\n", i);
  }
  
  for (i = 8 ; i < 16 ; i++) {
    IOWR_LED_DATA(LEDS_BASE, i, 3 << (32 - (i * 2)));
    printf("writing %x\n", i);
  }
  
  for (i = 0 ; i < 16 ; i++) {
    printf("reading %x = %x\n", i, IORD_LED_DATA(LEDS_BASE, i));
  }
  
  printf("Goodbye!\n");
    
  return 0;
}
