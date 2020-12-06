PROC=findcrypt3
O1=consts
O2=sparse
O3=operands
O4=hal_search

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)consts$(O)  : $(I)llong.hpp $(I)pro.h findcrypt3.hpp consts.cpp
$(F)sparse$(O)  : $(I)llong.hpp $(I)pro.h findcrypt3.hpp sparse.cpp
$(F)operands$(O): $(I)llong.hpp $(I)pro.h findcrypt3.hpp operands.cpp
$(F)hal_search$(O): $(I)llong.hpp $(I)pro.h findcrypt3.hpp hal_search.cpp

$(F)findcrypt3$(O): $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp             \
                  $(I)config.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp       \
                  $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
                  $(I)loader.hpp $(I)moves.hpp $(I)nalt.hpp $(I)name.hpp    \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp findcrypt3.cpp findcrypt3.hpp
