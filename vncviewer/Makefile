#
# Making the VNC applet.
#

JC = javac
JCFLAGS = -target 1.4 -source 1.4 -Xlint:deprecation
JAR = jar
ARCHIVE = VncViewer.jar
MANIFEST = MANIFEST.MF

CLASSES = VncViewer.class RfbProto.class VncCanvas.class \
	  OptionsFrame.class ClipboardFrame.class ButtonPanel.class \
	  CapabilityInfo.class CapsContainer.class \
	  InStream.class MemInStream.class ZlibInStream.class

SOURCES = VncViewer.java RfbProto.java VncCanvas.java \
	  OptionsFrame.java ClipboardFrame.java ButtonPanel.java \
	  CapabilityInfo.java CapsContainer.java \
	  InStream.java MemInStream.java ZlibInStream.java

all: $(CLASSES) $(ARCHIVE)

$(CLASSES): $(SOURCES)
	$(JC) $(JCFLAGS) -O $(SOURCES)

$(ARCHIVE): $(CLASSES) $(MANIFEST)
	$(JAR) cfm $(ARCHIVE) $(MANIFEST) $(CLASSES)

export:: $(CLASSES) $(ARCHIVE) $(PAGES)
	@$(ExportJavaClasses)

clean::
	$(RM) *.class *.jar
