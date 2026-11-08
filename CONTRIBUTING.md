# Contribution Guidelines

Please consider adding your name and github in the README's credit sections. Your work is valuable to us, and we want to credit you for the improvements you've made. 

## Translations
If you're making translations for our root-located README.md file, please make sure that you have the intention to be as accurate as possible. You can use the other translated files as a reference to guide you.

You don't have to actively maintain your translation, we will do it for you.

## Code contributions
The only rule is to be as simple as possible and document your intentions. 

We may rewrite your code so that it follows our internal guidelines, so don't worry about quality, just code your idea.

## I want to add a new technique, how would I do that?
You can use our add_technique.py script located in the `auxiliary` folder. The script will guide you.

If you want to do it manually, here's the steps that should be taken:
1. Make sure to add the technique name in the enums of all the techniques in the appropriate place.
2. Add the technique function itself in the technique section of the library. Make sure to add it in the right place, as there's preprocessor directives for each platform (Linux, Windows, and Apple).
3. Add the technique in the technique table situated at the end of the header file. The score should be between 10 and 100. You don't have to decide what the score should be; just put a random number and let that task to us.
4. Add it to the CLI's technique runner list.

If you couldn't do it successfully, don't worry; open the PR anyways. We will fix it for you.

## I want to contribute in any way but I'm not sure what to do or where to start
One of the main demands at the moment is creating cross-compatibility for techniques. Many techniques in the library are platform specific, but some of those can have shared detection vectors that are implementable on other platforms.

## Notes 
If you have any questions or inquiries, our contact details are in the README.