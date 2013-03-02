transcript on
if {[file exists rtl_work]} {
	vdel -lib rtl_work -all
}
vlib rtl_work
vmap work rtl_work

vcom -93 -work work {/home/user2/spring12/asc2171/csee4840/lab1/lab1.vhd}
vcom -93 -work work {/home/user2/spring12/asc2171/csee4840/lab1/raminfr.vhd}
vcom -93 -work work {/home/user2/spring12/asc2171/csee4840/lab1/hexdecoder.vhd}
vcom -93 -work work {/home/user2/spring12/asc2171/csee4840/lab1/ctrl.vhd}
vcom -93 -work work {/home/user2/spring12/asc2171/csee4840/lab1/DE2_TOP.vhd}

vcom -93 -work work {/home/user2/spring12/asc2171/csee4840/lab1/DE2_TOP_test.vhd}

vsim -t 1ps -L lpm -L altera -L altera_mf -L sgate -L cycloneii -L rtl_work -L work DE2_TOP_test

add wave *
view structure
view signals
run 1 sec
