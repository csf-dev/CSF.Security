namespace CSF.Security.Authentication
{
	public interface ICredentialsSerializer
	{
    object Deserialize(string serializedCredentials);

    string Serialize<TCredentials>(TCredentials credentials);
	}
}