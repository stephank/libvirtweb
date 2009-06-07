//
//  Copyright (C) 2001-2004 HorizonLive.com, Inc.  All Rights Reserved.
//  Copyright (C) 2002 Constantin Kaplinsky.  All Rights Reserved.
//  Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
//
//  This is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This software is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this software; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//

//
// VncViewer.java - the VNC viewer applet.  This class mainly just sets up the
// user interface, leaving it to the VncCanvas to do the actual rendering of
// a VNC desktop.
//

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;

public class VncViewer extends java.applet.Applet
  implements java.lang.Runnable, WindowListener {

  boolean inAnApplet = true;
  boolean inSeparateFrame = false;

  //
  // main() is called when run as a java program from the command line.
  // It simply runs the applet inside a newly-created frame.
  //

  public static void main(String[] argv) {
    VncViewer v = new VncViewer();
    v.mainArgs = argv;
    v.inAnApplet = false;
    v.inSeparateFrame = true;

    v.init();
    v.start();
  }

  String[] mainArgs;

  RfbProto rfb;
  Thread rfbThread;

  Frame vncFrame;
  Container vncContainer;
  ScrollPane desktopScrollPane;
  GridBagLayout gridbag;
  ButtonPanel buttonPanel;
  Label connStatusLabel;
  VncCanvas vc;
  OptionsFrame options;
  ClipboardFrame clipboard;

  // Variables read from parameter values.
  int port;
  byte[] cookieParam;
  boolean showControls;
  boolean showOfflineDesktop;
  int deferScreenUpdates;
  int deferCursorUpdates;
  int deferUpdateRequests;
  int debugStatsExcludeUpdates;
  int debugStatsMeasureUpdates;

  // Reference to this applet for inter-applet communication.
  public static java.applet.Applet refApplet;

  //
  // init()
  //

  public void init() {

    readParameters();

    refApplet = this;

    if (inSeparateFrame) {
      vncFrame = new Frame("TightVNC");
      if (!inAnApplet) {
	vncFrame.add("Center", this);
      }
      vncContainer = vncFrame;
    } else {
      vncContainer = this;
    }

    options = new OptionsFrame(this);
    clipboard = new ClipboardFrame(this);

    if (inSeparateFrame)
      vncFrame.addWindowListener(this);

    rfbThread = new Thread(this);
    rfbThread.start();
  }

  public void update(Graphics g) {
  }

  //
  // run() - executed by the rfbThread to deal with the RFB socket.
  //

  public void run() {

    gridbag = new GridBagLayout();
    vncContainer.setLayout(gridbag);

    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridwidth = GridBagConstraints.REMAINDER;
    gbc.anchor = GridBagConstraints.NORTHWEST;

    if (showControls) {
      buttonPanel = new ButtonPanel(this);
      gridbag.setConstraints(buttonPanel, gbc);
      vncContainer.add(buttonPanel);
    }

    try {
      connectAndAuthenticate();
      doProtocolInitialisation();

      // FIXME: Use auto-scaling not only in a separate frame.
      if (options.autoScale && inSeparateFrame) {
	Dimension screenSize;
	try {
	  screenSize = vncContainer.getToolkit().getScreenSize();
	} catch (Exception e) {
	  screenSize = new Dimension(0, 0);
	}
	createCanvas(screenSize.width - 32, screenSize.height - 32);
      } else {
	createCanvas(0, 0);
      }

      gbc.weightx = 1.0;
      gbc.weighty = 1.0;

      if (inSeparateFrame) {

	// Create a panel which itself is resizeable and can hold
	// non-resizeable VncCanvas component at the top left corner.
	Panel canvasPanel = new Panel();
	canvasPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
	canvasPanel.add(vc);

	// Create a ScrollPane which will hold a panel with VncCanvas
	// inside.
	desktopScrollPane = new ScrollPane(ScrollPane.SCROLLBARS_AS_NEEDED);
	gbc.fill = GridBagConstraints.BOTH;
	gridbag.setConstraints(desktopScrollPane, gbc);
	desktopScrollPane.add(canvasPanel);

	// Finally, add our ScrollPane to the Frame window.
	vncFrame.add(desktopScrollPane);
	vncFrame.setTitle(rfb.desktopName);
	vncFrame.pack();
	vc.resizeDesktopFrame();

      } else {

	// Just add the VncCanvas component to the Applet.
	gridbag.setConstraints(vc, gbc);
	add(vc);
	validate();

      }

      if (showControls)
	buttonPanel.enableButtons();

      moveFocusToDesktop();
      processNormalProtocol();

    } catch (NoRouteToHostException e) {
      fatalError("Network error: no route to server.", e);
    } catch (UnknownHostException e) {
      fatalError("Network error: server name unknown.", e);
    } catch (ConnectException e) {
      fatalError("Network error: could not connect to server.", e);
    } catch (EOFException e) {
      if (showOfflineDesktop) {
	e.printStackTrace();
	System.out.println("Network error: remote side closed connection");
	if (vc != null) {
	  vc.enableInput(false);
	}
	if (inSeparateFrame) {
	  vncFrame.setTitle(rfb.desktopName + " [disconnected]");
	}
	if (rfb != null && !rfb.closed())
	  rfb.close();
	if (showControls && buttonPanel != null) {
	  buttonPanel.disableButtonsOnDisconnect();
	  if (inSeparateFrame) {
	    vncFrame.pack();
	  } else {
	    validate();
	  }
	}
      } else {
	fatalError("Network error: remote side closed connection", e);
      }
    } catch (IOException e) {
      String str = e.getMessage();
      if (str != null && str.length() != 0) {
	fatalError("Network Error: " + str, e);
      } else {
	fatalError(e.toString(), e);
      }
    } catch (Exception e) {
      String str = e.getMessage();
      if (str != null && str.length() != 0) {
	fatalError("Error: " + str, e);
      } else {
	fatalError(e.toString(), e);
      }
    }
    
  }

  //
  // Create a VncCanvas instance.
  //

  void createCanvas(int maxWidth, int maxHeight) throws IOException {
    vc = new VncCanvas(this, maxWidth, maxHeight);
  }


  //
  // Process RFB socket messages.
  // If the rfbThread is being stopped, ignore any exceptions,
  // otherwise rethrow the exception so it can be handled.
  //
 
  void processNormalProtocol() throws Exception {
    try {
      vc.processNormalProtocol();
    } catch (Exception e) {
      if (rfbThread == null) {
	System.out.println("Ignoring RFB socket exceptions" +
			   " because applet is stopping");
      } else {
	throw e;
      }
    }
  }


  //
  // Connect to the RFB server and authenticate the user.
  //

  void connectAndAuthenticate() throws Exception
  {
    showConnectionStatus("Initializing...");
    if (inSeparateFrame) {
      vncFrame.pack();
      vncFrame.show();
    } else {
      validate();
    }

    showConnectionStatus("Connecting...");

    rfb = new RfbProto(getCodeBase().getHost(), 5900, this);
    showConnectionStatus("Connected to server");

    rfb.readVersionMsg();
    rfb.writeVersionMsg();

    int secType = rfb.negotiateSecurity();
    int authType;
    if (secType == RfbProto.SecTypeTight) {
      showConnectionStatus("Enabling TightVNC protocol extensions");
      rfb.setupTunneling();
      authType = rfb.negotiateAuthenticationTight();
    } else {
      authType = secType;
    }

    switch (authType) {
    case RfbProto.AuthNone:
      showConnectionStatus("No authentication needed");
      rfb.authenticateNone();
      break;
    case RfbProto.AuthAES:
      showConnectionStatus("Performing AES cookie authentication");
      rfb.authenticateAES(cookieParam);
      break;
    default:
      throw new Exception("Unknown authentication scheme " + authType);
    }
  }


  //
  // Show a message describing the connection status.
  // To hide the connection status label, use (msg == null).
  //

  void showConnectionStatus(String msg)
  {
    if (msg == null) {
      if (vncContainer.isAncestorOf(connStatusLabel)) {
	vncContainer.remove(connStatusLabel);
      }
      return;
    }

    System.out.println(msg);

    if (connStatusLabel == null) {
      connStatusLabel = new Label("Status: " + msg);
      connStatusLabel.setFont(new Font("Helvetica", Font.PLAIN, 12));
    } else {
      connStatusLabel.setText("Status: " + msg);
    }

    if (!vncContainer.isAncestorOf(connStatusLabel)) {
      GridBagConstraints gbc = new GridBagConstraints();
      gbc.gridwidth = GridBagConstraints.REMAINDER;
      gbc.fill = GridBagConstraints.HORIZONTAL;
      gbc.anchor = GridBagConstraints.NORTHWEST;
      gbc.weightx = 1.0;
      gbc.weighty = 1.0;
      gbc.insets = new Insets(20, 30, 20, 30);
      gridbag.setConstraints(connStatusLabel, gbc);
      vncContainer.add(connStatusLabel);
    }

    if (inSeparateFrame) {
      vncFrame.pack();
    } else {
      validate();
    }
  }


  //
  // Do the rest of the protocol initialisation.
  //

  void doProtocolInitialisation() throws IOException
  {
    rfb.writeClientInit();
    rfb.readServerInit();

    System.out.println("Desktop name is " + rfb.desktopName);
    System.out.println("Desktop size is " + rfb.framebufferWidth + " x " +
		       rfb.framebufferHeight);

    setEncodings();

    showConnectionStatus(null);
  }


  //
  // Send current encoding list to the RFB server.
  //

  int[] encodingsSaved;
  int nEncodingsSaved;

  void setEncodings()        { setEncodings(false); }
  void autoSelectEncodings() { setEncodings(true); }

  void setEncodings(boolean autoSelectOnly) {
    if (options == null || rfb == null || !rfb.inNormalProtocol)
      return;

    int preferredEncoding = options.preferredEncoding;
    if (preferredEncoding == -1) {
      long kbitsPerSecond = rfb.kbitsPerSecond();
      if (nEncodingsSaved < 1) {
        // Choose Tight or ZRLE encoding for the very first update.
        System.out.println("Using Tight/ZRLE encodings");
        preferredEncoding = RfbProto.EncodingTight;
      } else if (kbitsPerSecond > 2000 &&
                 encodingsSaved[0] != RfbProto.EncodingHextile) {
        // Switch to Hextile if the connection speed is above 2Mbps.
        System.out.println("Throughput " + kbitsPerSecond +
                           " kbit/s - changing to Hextile encoding");
        preferredEncoding = RfbProto.EncodingHextile;
      } else if (kbitsPerSecond < 1000 &&
                 encodingsSaved[0] != RfbProto.EncodingTight) {
        // Switch to Tight/ZRLE if the connection speed is below 1Mbps.
        System.out.println("Throughput " + kbitsPerSecond +
                           " kbit/s - changing to Tight/ZRLE encodings");
        preferredEncoding = RfbProto.EncodingTight;
      } else {
        // Don't change the encoder.
        if (autoSelectOnly)
          return;
        preferredEncoding = encodingsSaved[0];
      }
    } else {
      // Auto encoder selection is not enabled.
      if (autoSelectOnly)
        return;
    }

    int[] encodings = new int[20];
    int nEncodings = 0;

    encodings[nEncodings++] = preferredEncoding;
    if (options.useCopyRect) {
      encodings[nEncodings++] = RfbProto.EncodingCopyRect;
    }

    if (preferredEncoding != RfbProto.EncodingTight) {
      encodings[nEncodings++] = RfbProto.EncodingTight;
    }
    if (preferredEncoding != RfbProto.EncodingZRLE) {
      encodings[nEncodings++] = RfbProto.EncodingZRLE;
    }
    if (preferredEncoding != RfbProto.EncodingHextile) {
      encodings[nEncodings++] = RfbProto.EncodingHextile;
    }
    if (preferredEncoding != RfbProto.EncodingZlib) {
      encodings[nEncodings++] = RfbProto.EncodingZlib;
    }
    if (preferredEncoding != RfbProto.EncodingCoRRE) {
      encodings[nEncodings++] = RfbProto.EncodingCoRRE;
    }
    if (preferredEncoding != RfbProto.EncodingRRE) {
      encodings[nEncodings++] = RfbProto.EncodingRRE;
    }

    if (options.compressLevel >= 0 && options.compressLevel <= 9) {
      encodings[nEncodings++] =
        RfbProto.EncodingCompressLevel0 + options.compressLevel;
    }
    if (options.jpegQuality >= 0 && options.jpegQuality <= 9) {
      encodings[nEncodings++] =
        RfbProto.EncodingQualityLevel0 + options.jpegQuality;
    }

    if (options.requestCursorUpdates) {
      encodings[nEncodings++] = RfbProto.EncodingXCursor;
      encodings[nEncodings++] = RfbProto.EncodingRichCursor;
      if (!options.ignoreCursorUpdates)
	encodings[nEncodings++] = RfbProto.EncodingPointerPos;
    }

    encodings[nEncodings++] = RfbProto.EncodingLastRect;
    encodings[nEncodings++] = RfbProto.EncodingNewFBSize;

    boolean encodingsWereChanged = false;
    if (nEncodings != nEncodingsSaved) {
      encodingsWereChanged = true;
    } else {
      for (int i = 0; i < nEncodings; i++) {
        if (encodings[i] != encodingsSaved[i]) {
          encodingsWereChanged = true;
          break;
        }
      }
    }

    if (encodingsWereChanged) {
      try {
        rfb.writeSetEncodings(encodings, nEncodings);
        if (vc != null) {
          vc.softCursorFree();
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
      encodingsSaved = encodings;
      nEncodingsSaved = nEncodings;
    }
  }


  //
  // setCutText() - send the given cut text to the RFB server.
  //

  void setCutText(String text) {
    try {
      if (rfb != null && rfb.inNormalProtocol) {
	rfb.writeClientCutText(text);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  //
  // readParameters() - read parameters from the html source or from the
  // command line.  On the command line, the arguments are just a sequence of
  // param_name/param_value pairs where the names and values correspond to
  // those expected in the html applet tag source.
  //

  void readParameters() {
    port = readIntParameter("PORT", 5900);

    String hexcookie = readParameter("COOKIE", true);
    // COOKIE is hexascii-encoded. Decode.
    if (hexcookie.length() != 32)
      fatalError("COOKIE parameter needs to be 32 hexdigits in length");
    cookieParam = new byte[16];
    for (int i = 0; i < 16; i++) {
      String hex = hexcookie.substring(i*2, i*2+2);
      Integer x = new Integer(Integer.parseInt(hex, 16));
      cookieParam[i] = x.byteValue();
    }

    String str;
    if (inAnApplet) {
      str = readParameter("Open New Window", false);
      if (str != null && str.equalsIgnoreCase("Yes"))
	inSeparateFrame = true;
    }

    // "Show Controls" set to "No" disables button panel.
    showControls = true;
    str = readParameter("Show Controls", false);
    if (str != null && str.equalsIgnoreCase("No"))
      showControls = false;

    // Do we continue showing desktop on remote disconnect?
    showOfflineDesktop = false;
    str = readParameter("Show Offline Desktop", false);
    if (str != null && str.equalsIgnoreCase("Yes"))
      showOfflineDesktop = true;

    // Fine tuning options.
    deferScreenUpdates = readIntParameter("Defer screen updates", 20);
    deferCursorUpdates = readIntParameter("Defer cursor updates", 10);
    deferUpdateRequests = readIntParameter("Defer update requests", 0);

    // Debugging options.
    debugStatsExcludeUpdates = readIntParameter("DEBUG_XU", 0);
    debugStatsMeasureUpdates = readIntParameter("DEBUG_CU", 0);
  }

  public String readParameter(String name, boolean required) {
      String s = getParameter(name);
      if ((s == null) && required) {
	fatalError(name + " parameter not specified");
      }
      return s;
  }

  int readIntParameter(String name, int defaultValue) {
    String str = readParameter(name, false);
    int result = defaultValue;
    if (str != null) {
      try {
	result = Integer.parseInt(str);
      } catch (NumberFormatException e) { }
    }
    return result;
  }

  //
  // moveFocusToDesktop() - move keyboard focus either to VncCanvas.
  //

  void moveFocusToDesktop() {
    if (vncContainer != null) {
      if (vc != null && vncContainer.isAncestorOf(vc))
	vc.requestFocus();
    }
  }

  //
  // disconnect() - close connection to server.
  //

  synchronized public void disconnect() {
    System.out.println("Disconnecting");

    if (vc != null) {
      double sec = (System.currentTimeMillis() - vc.statStartTime) / 1000.0;
      double rate = Math.round(vc.statNumUpdates / sec * 100) / 100.0;
      int nRealRects = vc.statNumPixelRects;
      int nPseudoRects = vc.statNumTotalRects - vc.statNumPixelRects;
      System.out.println("Updates received: " + vc.statNumUpdates + " (" +
                         nRealRects + " rectangles + " + nPseudoRects +
                         " pseudo), " + rate + " updates/sec");
      int numRectsOther = nRealRects - vc.statNumRectsTight
        - vc.statNumRectsZRLE - vc.statNumRectsHextile
        - vc.statNumRectsRaw - vc.statNumRectsCopy;
      System.out.println("Rectangles:" +
                         " Tight=" + vc.statNumRectsTight +
                         "(JPEG=" + vc.statNumRectsTightJPEG +
                         ") ZRLE=" + vc.statNumRectsZRLE +
                         " Hextile=" + vc.statNumRectsHextile +
                         " Raw=" + vc.statNumRectsRaw +
                         " CopyRect=" + vc.statNumRectsCopy +
                         " other=" + numRectsOther);

      int raw = vc.statNumBytesDecoded;
      int compressed = vc.statNumBytesEncoded;
      if (compressed > 0) {
          double ratio = Math.round((double)raw / compressed * 1000) / 1000.0;
          System.out.println("Pixel data: " + vc.statNumBytesDecoded +
                             " bytes, " + vc.statNumBytesEncoded +
                             " compressed, ratio " + ratio);
      }
    }

    if (rfb != null && !rfb.closed())
      rfb.close();
    options.dispose();
    clipboard.dispose();

    if (inAnApplet) {
      showMessage("Disconnected");
    } else {
      System.exit(0);
    }
  }

  //
  // fatalError() - print out a fatal error message.
  // FIXME: Do we really need two versions of the fatalError() method?
  //

  synchronized public void fatalError(String str) {
    System.out.println(str);

    if (inAnApplet) {
      // vncContainer null, applet not inited,
      // can not present the error to the user.
      Thread.currentThread().stop();
    } else {
      System.exit(1);
    }
  }

  synchronized public void fatalError(String str, Exception e) {
 
    if (rfb != null && rfb.closed()) {
      // Not necessary to show error message if the error was caused
      // by I/O problems after the rfb.close() method call.
      System.out.println("RFB thread finished");
      return;
    }

    System.out.println(str);
    e.printStackTrace();

    if (rfb != null)
      rfb.close();

    if (inAnApplet) {
      showMessage(str);
    } else {
      System.exit(1);
    }
  }

  //
  // Show message text
  //

  void showMessage(String msg) {
    vncContainer.removeAll();

    Label errLabel = new Label(msg, Label.CENTER);
    errLabel.setFont(new Font("Helvetica", Font.PLAIN, 12));

    vncContainer.setLayout(new FlowLayout(FlowLayout.LEFT, 30, 30));
    vncContainer.add(errLabel);

    if (inSeparateFrame) {
      vncFrame.pack();
    } else {
      validate();
    }
  }

  //
  // Stop the applet.
  // Main applet thread will terminate on first exception
  // after seeing that rfbThread has been set to null.
  //

  public void stop() {
    System.out.println("Stopping applet");
    rfbThread = null;
  }

  //
  // This method is called before the applet is destroyed.
  //

  public void destroy() {
    System.out.println("Destroying applet");

    vncContainer.removeAll();
    options.dispose();
    clipboard.dispose();
    if (rfb != null && !rfb.closed())
      rfb.close();
    if (inSeparateFrame)
      vncFrame.dispose();
  }

  //
  // Start/stop receiving mouse events.
  //

  public void enableInput(boolean enable) {
    vc.enableInput(enable);
  }

  //
  // Close application properly on window close event.
  //

  public void windowClosing(WindowEvent evt) {
    System.out.println("Closing window");
    if (rfb != null)
      disconnect();

    vncContainer.hide();

    if (!inAnApplet) {
      System.exit(0);
    }
  }

  //
  // Ignore window events we're not interested in.
  //

  public void windowActivated(WindowEvent evt) {}
  public void windowDeactivated (WindowEvent evt) {}
  public void windowOpened(WindowEvent evt) {}
  public void windowClosed(WindowEvent evt) {}
  public void windowIconified(WindowEvent evt) {}
  public void windowDeiconified(WindowEvent evt) {}
}