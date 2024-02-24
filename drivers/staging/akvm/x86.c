#include "common.h"
#include "x86.h"

enum x86_excep_class {
	X86_EXCEP_BENIGN = 1,
	X86_EXCEP_CONTRIBUTORY,
	X86_EXCEP_PAGE_FAULT,
};

static enum x86_excep_class x86_excep_class(int excep_number)
{
	switch(excep_number) {
	case X86_EXCEP_DE:
	case X86_EXCEP_TS:
	case X86_EXCEP_NP:
	case X86_EXCEP_SS:
	case X86_EXCEP_GP:
	case X86_EXCEP_CP:
		return X86_EXCEP_CONTRIBUTORY;
	case X86_EXCEP_PF:
	case X86_EXCEP_VE:
		return X86_EXCEP_PAGE_FAULT;
	default:
		return X86_EXCEP_BENIGN;
	}
}

bool x86_excep_df(int excep_1, int excep_2)
{
	enum x86_excep_class class_1;
	enum x86_excep_class class_2;

	class_1 = x86_excep_class(excep_1);
	class_2 = x86_excep_class(excep_2);

	if (class_1 == X86_EXCEP_CONTRIBUTORY &&
	    class_1 == class_2)
		return true;

	if (class_1 == X86_EXCEP_PAGE_FAULT &&
	    (class_2 == X86_EXCEP_CONTRIBUTORY || class_1 == class_2))
		return true;

	return false;
}

enum x86_event_type x86_excep_event_type(int excep_number)
{
	WARN_ON(excep_number > X86_EXCEP_END);

	if (excep_number == X86_EXCEP_BP ||
	    excep_number == X86_EXCEP_OF)
		return X86_EVENT_SOFTWARE_EXCEP;

	if (excep_number == X86_EXCEP_NMI)
		return X86_EVENT_NMI;

	/*#DB treates as hardwar exception, not priv software exception */
	return X86_EVENT_HARDWARE_EXCEP;
}
