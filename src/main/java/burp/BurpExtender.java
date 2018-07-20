package burp;

import java.io.PrintWriter;

import jwmoon.SQLTabFactory;
import jwmoon.XSSTabFactory;

public class BurpExtender implements IBurpExtender{

	private XSSTabFactory factory1;
	private SQLTabFactory factory2;
	
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
    	
        callbacks.setExtensionName("Fuzzler");
        factory1 = new XSSTabFactory(callbacks);
        factory2 = new SQLTabFactory(callbacks);
        callbacks.registerMessageEditorTabFactory(factory1);
        callbacks.registerMessageEditorTabFactory(factory2);
        
        stdout.println("Installation complete.");
    }

   
}