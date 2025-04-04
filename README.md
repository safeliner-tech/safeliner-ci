## What is Safeliner?
Safeliner is a SaaS tool which helps you to mitigate vulnerabilities in your code. Like a dependabot helps you to keep your dependencies up to date, Safeliner produces autofixes for security issues found by static analyzers. Actually it is not only limited to static tools - if any tool or person can provide a details of a vulnerability, Safeliner can fix it.

## Key Safeliner Features
* Safeliner can make a triage and say if the finding is true or false and explain why it is false
* Safeliner can explain the finding, which risk it may pose and why it is important to fix it
* Safeliner can finally fix the issue

## Are you ready to use it?
1. First of all, you need a SAST tool which produce a vulnerability report in a SARIF format (e.g. Semgrep, CodeQL and etc)
2. Second, drop a letter to us, we will provide you with a Safeliner credentials
3. Third, you have to import a workflow with Safeliner and run it regularly against you repository

## I'm already interested, what's next?
Please email us safeliner@t-technologies.ru and we will setup a Demo account for you. It is free. The only fee we ask is a feedback ;)

## How to setup Safeliner?
1. Configure the following CI variables in your repository (we will provide it for you)
* SAFELINER_APP_ID - an ID of Safeliner GitHub application
* SAFELINER_IMAGE_VERSION - up to date image version of Safeliner (default version is already set in the workflow)
2. Configure the following secrets in your repository (we will provide it for you)
* SAFELINER_APP_SECRET - a secret of Safeliner GitHub application
* SAFELINER_API_TOKEN - a token for Safeliner API
3. Copy the [workflow template](.github/workflows/safeliner.yml) to your repository. It may not necessarily be the same repo where you want to make fixes.
4. Setup env variables in the workflow:
* REPO_OWNER - owner of the repository
* REPO_NAME - name of the repository
* GENERATED_BRANCH_NAME - name pattern of the new branch where fixes will be applied
* GENERATED_PR_TITLE - title of the pull request Safeliner will open with fixes
* PR_TARGET_BRANCH - name of the base repo branch to make fixes (and target for the Safeliner PR)
5. Schedule periodic workflow runs and that's it!

## FAQ
* *Which SAST scanner to use?*  
We have a bundled Semgrep scanner in the [Safeliner image](Dockerfile). If you have any other SARIF compatible scanner, just install it to the image and slightly modify the workflow. The rest of integration script will work.
* *How do we check if the fix actually closes the gap?*  
After applying the fix we re-run SAST tool and check if the finding resolved. Just see [integration script](/src/integration.py) for the details.
* *Do we store your source code?*  
Nope. We calculate only analytical data and the feedback (see the feedback handler in [integration script](/src/integration.py)). We do not store our customers source code.
* *Can I write my own integration script or application and use the pure Safeliner API?*  
Yes, of course! It is fully up to you how to integrate the Safeliner into your SDLC! We just provide you with an example and quick start pack the rest is up to your creativity and imagination.

## I still have problems or questions, what to do?
We are glad to hear you - safeliner@t-technologies.ru