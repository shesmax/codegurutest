import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MatcherTest 
{
	public static void main(String[] args)
	{
		Pattern p = Pattern.compile("\\d\\d\\d\\d");
		Matcher m = p.matcher("");
		
		System.out.println("Empty string matches to 4 digits: " + m.matches());
		
		String subject = "CCN'S 739535 &739534 [#12614118]";
		System.out.println(getProperty(subject, "0"));
		System.out.println(getProperty(subject, "1"));

		String[] scopes = {
				"abc.abc.abc",
				"IoT.Things.Any.All.Write/onboard",
				"IoT.Things.Any.MyCurrentAccount.Write/onboard",
				"IoT.Things.tags:.+.All.Write/onboard",
				"IoT.Things.tags:.+.MyCurrentAccount.Write/onboard",
				"IoT.Things.tags:ontrack.All.Write/onboard",
				"IoT.Things.tags:ontrack.MyCurrentAccount.Write/onboard",
				"IoT.Things.Any.All.Write/mapping",
				"IoT.Things.Any.All.Read/mapping"
		};
		Pattern[] patterns = {
			Pattern.compile("(^|\\s)IoT\\.Things\\.Any\\.All\\.Write/onboard(\\s|$)"),
			Pattern.compile("(^|\\s)IoT\\.Things\\..+\\.MyCurrentAccount\\.Write/onboard(\\s|$)"),
			Pattern.compile("(^|\\s)IoT\\.Things\\.tags:\\.\\+\\..+\\.Write/onboard(\\s|$)"),
			Pattern.compile("(^|\\s)IoT\\.Things\\.tags:ontrack\\..+\\.Write/onboard(\\s|$)"),
			Pattern.compile("(^|\\s)IoT\\.Things\\.Any\\.All\\.Read/mapping(\\s|$)"),
			Pattern.compile("(^|\\s)IoT\\.Things\\.Any\\.All\\.Write/mapping(\\s|$)")
		};

		for (String raw_scope: scopes) {
			String scope = "s1.s1.s1 s2.s.s2 " + raw_scope + " some.other.scopes";
			System.out.print(raw_scope);
			for (int i = raw_scope.length(); i < 60; ++i)
				System.out.print(" ");

			for (Pattern pattern: patterns) {
				System.out.print("\t" + pattern.matcher(scope).find());
			}
			System.out.println("");
		}
	}
	
	static String getProperty(String subject, String sIdx)
	{
	int idx = Integer.parseInt(sIdx);		

	if (idx < 0 || idx > 1)
		return "";
		
	if (subject.length() > 3 && subject.substring(2, 3).equals(":"))
		subject = subject.substring(3).trim();

	if (subject.startsWith("_"))
		subject = subject.replaceAll("_", " ").trim();	

	String props[] = subject.split(" +");
	if (props == null || props.length < 1)
	   return ""; 
		   				
	// If there is <country code><document id> w/o space in between, split them into two elements.
	if (props[0].length() > 3 && props[0].matches("[A-Za-z][A-Za-z][A-Za-z0-9]\\d+")) 
		return idx == 0 ? props[0].substring(0, 2) : props[0].substring(2);
	return idx >= props.length ? "" : props[idx].trim();
	}

	private static void examineScopes(final String raw_scopes, final Pattern pattern)
	{

	}

}
