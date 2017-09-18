package pukiwikiCommunicator.language;

public interface InterpreterInterface
{
	public String getOutputText();
	public boolean isTracing();
	public String parseCommand(String x);
	public InterpreterInterface lookUp(String x);
}
