package jwmoon;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.IRequestInfo;
import burp.ITextEditor;

public class SQLTabFactory implements IMessageEditorTabFactory{

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
    private PrintWriter stdout;
	
	
    public SQLTabFactory(IBurpExtenderCallbacks callbacks) {
    	this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        return new SQLTab(controller, editable);
    }
	
	class SQLTab implements IMessageEditorTab{
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        public SQLTab(IMessageEditorController controller, boolean editable)
        {
            this.editable = editable;
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        @Override
        public String getTabCaption()
        {
            return "SQL Injection test";
        }

        @Override
        public Component getUiComponent()
        {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest)
        {
        	return isRequest;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                txtInput.setText(null);
                txtInput.setEditable(false);
            }else{
                IRequestInfo reqInfo = helpers.analyzeRequest(content);
                List<IParameter> params = reqInfo.getParameters();
                
                // sql injection payloads
                for(int i=0; i < params.size(); i++) {
                	IParameter param = params.get(i);
                	if(!param.getName().equals("JSESSIONID")) {
	                	content = helpers.updateParameter(
	                			content, helpers.buildParameter(param.getName(), "'", IParameter.PARAM_BODY));
                	}
                }
                txtInput.setText(content);
                txtInput.setEditable(editable);
            }
            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage()
        {
        	return currentMessage;
        }

        @Override
        public boolean isModified()
        {
            //return txtInput.isTextModified();
        	return false; //always
        }

        @Override
        public byte[] getSelectedData()
        {
            return txtInput.getSelectedText();
        }
    }
}