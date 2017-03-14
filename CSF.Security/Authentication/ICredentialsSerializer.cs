namespace CSF.Security.Authentication
{
  /// <summary>
  /// A service which serializes and deserializes a credentials object to/from a string (for storage in a database).
  /// </summary>
	public interface ICredentialsSerializer
	{
    /// <summary>
    /// Deserialize the specified serialized credentials string.
    /// </summary>
    /// <param name="serializedCredentials">Serialized credentials.</param>
    object Deserialize(string serializedCredentials);

    /// <summary>
    /// Serialize the specified credentials to a string.
    /// </summary>
    /// <param name="credentials">Credentials.</param>
    /// <typeparam name="TCredentials">The credentials type.</typeparam>
    string Serialize<TCredentials>(TCredentials credentials);
	}
}