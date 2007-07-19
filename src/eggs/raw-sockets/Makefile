EGG = raw-sockets

all: $(EGG).egg

$(EGG).egg: $(EGG).html $(EGG).scm $(EGG).setup
	tar cf ../../../eggs/$(EGG).egg $(EGG).html $(EGG).scm $(EGG).setup

clean:
	rm -f ../../../eggs/$(EGG).egg

