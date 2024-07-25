import streamlit as st
import pandas as pd
import hashlib

from langchain_core.messages import AIMessage, HumanMessage
from langchain_community.document_loaders import WebBaseLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.chains import create_history_aware_retriever, create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain

load_dotenv()

# Initialize the dictionary to store chat histories by URL
chat_histories = {}

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to get user data
def get_user_data():
    try:
        user_data = pd.read_csv('users.csv', index_col='username')
        if 'privilege' not in user_data.columns:
            user_data['privilege'] = 'user'  # Default to 'user' if 'privilege' column is missing
        return user_data
    except FileNotFoundError:
        return pd.DataFrame(columns=['username', 'password', 'status', 'privilege']).set_index('username')
    except pd.errors.ParserError:
        st.error("Error parsing the users.csv file. Please ensure it is correctly formatted.")
        return pd.DataFrame(columns=['username', 'password', 'status', 'privilege']).set_index('username')

# Function to verify credentials and get user status and privilege
def check_credentials(username, password):
    user_data = get_user_data()
    if username in user_data.index:
        stored_password_hash = user_data.loc[username, 'password']
        if hash_password(password) == stored_password_hash:
            return user_data.loc[username, 'status'], user_data.loc[username, 'privilege']
    return None, None

# Function to register new user by self-registration
def self_register_user(username, password):
    user_data = get_user_data()
    if username in user_data.index:
        return False  # Username already exists
    else:
        user_data.loc[username] = [hash_password(password), 'pending', 'user']
        user_data.to_csv('users.csv')
        return True

# Function to register new user by admin
def register_user_from_admin(username, password, privilege='user'):
    user_data = get_user_data()
    if username in user_data.index:
        return False  # Username already exists
    else:
        user_data.loc[username] = [hash_password(password), 'pending', privilege]
        user_data.to_csv('users.csv')
        return True

# Function to delete a user
def delete_user(username):
    user_data = get_user_data()
    if username in user_data.index:
        user_data = user_data.drop(username)
        user_data.to_csv('users.csv')
        return True
    return False

# Function to load chat history for a session (URL)
def load_chat_history(username):
    try:
        chat_data = pd.read_csv('chat_history.csv', index_col='username')
        if username in chat_data.index:
            return eval(chat_data.loc[username, 'chat_history'])
        else:
            return {}
    except FileNotFoundError:
        return {}
    except pd.errors.ParserError:
        st.error("Error parsing the chat_history.csv file. Please ensure it is correctly formatted.")
        return {}

# Function to save chat history for a session (URL)
def save_chat_history(username, url, chat_history):
    try:
        chat_data = pd.read_csv('chat_history.csv', index_col='username')
    except FileNotFoundError:
        chat_data = pd.DataFrame(columns=['username', 'chat_history'])
        chat_data.set_index('username', inplace=True)

    if username in chat_data.index:
        user_chats = eval(chat_data.loc[username, 'chat_history'])
    else:
        user_chats = {}

    user_chats[url] = chat_history
    chat_data.loc[username, 'chat_history'] = str(user_chats)
    chat_data.to_csv('chat_history.csv')

# Function to delete chat history for a session (URL)
def delete_chat_history(username, url):
    try:
        chat_data = pd.read_csv('chat_history.csv', index_col='username')
        if username in chat_data.index:
            user_chats = eval(chat_data.loc[username, 'chat_history'])
            if url in user_chats:
                del user_chats[url]
                chat_data.loc[username, 'chat_history'] = str(user_chats)
                chat_data.to_csv('chat_history.csv')
                return True
        return False
    except FileNotFoundError:
        return False

# Set page config at the beginning
st.set_page_config(page_title="Dashboard", page_icon="🧠", layout="wide")

# Adding custom CSS for better UI/UX
st.markdown("""
    <style>
        .sidebar .sidebar-content {
            background-color: #3a3f44;
        }
        .sidebar .sidebar-content h1 {
            color: white;
        }
        .sidebar .sidebar-content a {
            color: white;
        }
        .main .block-container {
            padding: 2rem;
        }
        h1, h2, h3, h4, h5, h6 {
            color: #0d6efd;
        }
        .css-18e3th9 {
            padding-top: 2rem;
        }
        .large-font {
            font-size: 40px !important;
        }
        .larger-font {
            font-size: 20px !important;
        }
        .blue-text {
            color: blue;
        }
        .orange-text {
            color: orange;
        }
        .red-text {
            color: red;
        }
        .green-text {
            color: green;
        }
        .larger-table .stDataFrame {
            font-size: 1.5rem !important;
        }
    </style>
    """, unsafe_allow_html=True)

def main():
    if 'username' in st.session_state:
        user_data = get_user_data()
        privilege = user_data.loc[st.session_state['username'], 'privilege']
        
        if privilege == 'admin':
            admin_dashboard()
        else:
            user_dashboard()
    else:
        if 'navigation' in st.session_state and st.session_state['navigation'] == 'register':
            registration_page()
        else:
            login_page()

def login_page():
    st.markdown("<h2 style='text-align: center;'>Login</h2>", unsafe_allow_html=True)
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    if st.button('Login'):
        status, privilege = check_credentials(username, password)
        if status:
            if status == 'blocked':
                st.error('You have been blocked')
            elif status == 'declined':
                st.error('You have been declined. Contact the administration.')
            elif status == 'pending':
                st.warning('Your account is pending approval. Please contact the administration.')
            else:
                st.session_state.username = username
                st.session_state.privilege = privilege
                st.success('Logged in successfully.')
                st.experimental_rerun()
        else:
            st.error('Incorrect Username/Password')

    if st.button('Register New Account'):
        st.session_state.navigation = 'register'
        st.experimental_rerun()

def registration_page():
    st.markdown("<h2 style='text-align: center;'>Register New Account</h2>", unsafe_allow_html=True)
    new_username = st.text_input('New Username', key='reg_new_username')
    new_password = st.text_input('New Password', type='password', key='reg_new_password')
    confirm_password = st.text_input('Confirm Password', type='password', key='reg_confirm_password')
    if st.button('Register'):
        if new_password == confirm_password:
            if self_register_user(new_username, new_password):
                st.success('You have successfully registered. Your account is pending approval.')
                st.session_state.navigation = 'login'
                st.experimental_rerun()
            else:
                st.error('Username already exists')
        else:
            st.error('Passwords do not match')

    if st.button('Back to Login'):
        st.session_state.navigation = 'login'
        st.experimental_rerun()

def logout():
    del st.session_state['username']
    del st.session_state['privilege']
    st.success("You've been logged out")
    st.experimental_rerun()

def admin_dashboard():
    tabs = st.tabs(["Dashboard", "User Management", "View User Chat History", "Register User", "Manage Roles"])

    with tabs[0]:
        dashboard_page()
    
    with tabs[1]:
        user_management_page()
    
    with tabs[2]:
        view_chat_history_page()
    
    with tabs[3]:
        register_user_page()
    
    with tabs[4]:
        manage_roles_page()

def dashboard_page():
    st.markdown("<h2 style='text-align: center;'>Dashboard</h2>", unsafe_allow_html=True)
    user_data = get_user_data()
    total_users = len(user_data)
    approved_count = len(user_data[user_data['status'] == 'approved'])
    declined_count = len(user_data[user_data['status'] == 'declined'])
    blocked_count = len(user_data[user_data['status'] == 'blocked'])
    admin_count = len(user_data[user_data['privilege'] == 'admin'])
    admin_names = user_data[user_data['privilege'] == 'admin'].index.tolist()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"<p class='large-font'>Total Users: {total_users}</p>", unsafe_allow_html=True)
        st.markdown(f"<p class='large-font blue-text'>Approved Users: {approved_count}</p>", unsafe_allow_html=True)
        st.markdown(f"<p class='large-font orange-text'>Declined Users: {declined_count}</p>", unsafe_allow_html=True)
        st.markdown(f"<p class='large-font red-text'>Blocked Users: {blocked_count}</p>", unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"<p class='large-font'>Admin Users: {admin_count}</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='green-text'>Admin User List</h3>", unsafe_allow_html=True)
        st.markdown(f"<p class='larger-font'>{'<br>'.join(admin_names)}</p>", unsafe_allow_html=True)

    if st.button("Logout"):
        logout()

def user_dashboard():
    with st.sidebar:
        st.write(f"Logged in as {st.session_state['username']}")
        menu_option = st.selectbox("Navigation", ["Chat", "Account", "Logout"])
        if menu_option == "Logout":
            logout()
        elif menu_option == "Account":
            st.session_state['navigation'] = 'account'
        elif menu_option == "Chat":
            st.session_state['navigation'] = 'home'
    
    if st.session_state.get('navigation') == 'home':
        home_page()
    elif st.session_state.get('navigation') == 'account':
        account_page()

def home_page():
    st.subheader('Chatting')
    st.write(f"Hey, {st.session_state.get('username', 'Guest')}! Now you can chat with me, ask me something about the link")

    def get_vectorstore_from_url(url):
        # get the text in document form
        loader = WebBaseLoader(url)
        document = loader.load()
        
        # split the document into chunks
        text_splitter = RecursiveCharacterTextSplitter()
        document_chunks = text_splitter.split_documents(document)
        
        # create a vectorstore from the chunks
        vector_store = Chroma.from_documents(document_chunks, OpenAIEmbeddings())

        return vector_store

    def get_context_retriever_chain(vector_store):
        llm = ChatOpenAI()
        
        retriever = vector_store.as_retriever()
        
        prompt = ChatPromptTemplate.from_messages([
        MessagesPlaceholder(variable_name="chat_history"),
        ("user", "{input}"),
        ("user", "Given the above conversation, generate a search query to look up in order to get information relevant to the conversation")
        ])
        
        retriever_chain = create_history_aware_retriever(llm, retriever, prompt)
        
        return retriever_chain
        
    def get_conversational_rag_chain(retriever_chain): 
        
        llm = ChatOpenAI()
        
        prompt = ChatPromptTemplate.from_messages([
        ("system", "Answer the user's questions based on the below context:\n\n{context}"),
        MessagesPlaceholder(variable_name="chat_history"),
        ("user", "{input}"),
        ])
        
        stuff_documents_chain = create_stuff_documents_chain(llm,prompt)
        
        return create_retrieval_chain(retriever_chain, stuff_documents_chain)

    def get_response(user_input):
        retriever_chain = get_context_retriever_chain(st.session_state.vector_store)
        conversation_rag_chain = get_conversational_rag_chain(retriever_chain)
        
        response = conversation_rag_chain.invoke({
            "chat_history": st.session_state.chat_history,
            "input": user_input
        })
        
        return response['answer']

    # app config
    #st.set_page_config(page_title="Chat with websites", page_icon="🤖")
    #st.title("Chat with websites")

    # sidebar
    with st.sidebar:
        st.header("Settings")
        website_url = st.text_input("Website URL")

    if website_url is None or website_url == "":
        st.info("Please enter a website URL")

    else:
        # session state
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = [
                AIMessage(content="Hello, I am a bot. How can I help you?"),
            ]
        if "vector_store" not in st.session_state:
            st.session_state.vector_store = get_vectorstore_from_url(website_url)    

        # user input
        user_query = st.chat_input("Type your message here...")
        if user_query is not None and user_query != "":
            response = get_response(user_query)
            st.session_state.chat_history.append(HumanMessage(content=user_query))
            st.session_state.chat_history.append(AIMessage(content=response))
            save_chat_history(st.session_state['username'], website_url, st.session_state.chat_history)
        

        # conversation
        for message in st.session_state.chat_history:
            if isinstance(message, AIMessage):
                with st.chat_message("AI"):
                    st.write(message.content)
            elif isinstance(message, HumanMessage):
                with st.chat_message("Human"):
                    st.write(message.content)

def account_page():
    st.subheader('Account Details')
    st.write(f"Welcome {st.session_state['username']}! This is your account page.")

    # Load all chat histories for the user
    all_chat_histories = load_chat_history(st.session_state['username'])
    
    for url, chat_history in all_chat_histories.items():
        st.markdown(f"### Chat history for URL: {url}")
        for message in chat_history:
            if isinstance(message, AIMessage):
                st.markdown(f"**AI:** {message.content}")
            elif isinstance(message, HumanMessage):
                st.markdown(f"**{st.session_state['username']}:** {message.content}")

    if st.button('Delete All Chat History'):
        for url in list(all_chat_histories.keys()):
            delete_chat_history(st.session_state['username'], url)
        st.success("All chat histories have been deleted.")
        st.session_state.chat_history = []

def user_management_page():
    st.markdown("<h2 style='text-align: center;'>User Management</h2>", unsafe_allow_html=True)
    st.write("Manage users and their access to the app.")

    user_data = get_user_data()
    
    if user_data.empty:
        st.write("No users found.")
    else:
        approved_count = len(user_data[user_data['status'] == 'approved'])
        declined_count = len(user_data[user_data['status'] == 'declined'])
        blocked_count = len(user_data[user_data['status'] == 'blocked'])
        total_users = len(user_data)

        col1, col2, col3 = st.columns(3)

        with col1:
            st.write("### User Data")
            user_data_no_password = user_data.drop(columns=['password'])
            st.markdown('<div class="larger-table">', unsafe_allow_html=True)
            st.dataframe(user_data_no_password)
            st.markdown('</div>', unsafe_allow_html=True)

        with col2:
            st.write("### User Management")
            user_to_update = st.selectbox("Select a user to update", user_data.index, key="user_management_user_select")
            new_status = st.selectbox("Select new status", ["approved", "declined", "blocked"], key="user_management_status_select")

            if st.button("Update Status"):
                user_data.loc[user_to_update, 'status'] = new_status
                user_data.to_csv('users.csv')
                st.success(f"Updated {user_to_update}'s status to {new_status}")

            if st.button("Delete User"):
                if delete_user(user_to_update):
                    st.success(f"Deleted user {user_to_update}")
                    st.experimental_rerun()
                else:
                    st.error("Failed to delete user")

        with col3:
            st.markdown(f"<p class='large-font'>Total Users: {total_users}</p>", unsafe_allow_html=True)
            st.write(f"Approved Users: {approved_count}")
            st.write(f"Declined Users: {declined_count}")
            st.write(f"Blocked Users: {blocked_count}")

def view_chat_history_page():
    st.markdown("<h2 style='text-align: center;'>View User Chat History</h2>", unsafe_allow_html=True)
    st.write("Select a user to view their chat history.")

    user_data = get_user_data()

    if user_data.empty:
        st.write("No users found.")
    else:
        user_to_view = st.selectbox("Select a user", user_data.index, key="view_chat_history_user_select")

        if st.button("View Chat History"):
            all_chat_histories = load_chat_history(user_to_view)
            for url, chat_history in all_chat_histories.items():
                st.markdown(f"### Chat history for URL: {url}")
                for message in chat_history:
                    if isinstance(message, AIMessage):
                        st.markdown(f"**AI:** {message.content}")
                    elif isinstance(message, HumanMessage):
                        st.markdown(f"**{user_to_view}:** {message.content}")

def register_user_page():
    st.markdown("<h2 style='text-align: center;'>Register User</h2>", unsafe_allow_html=True)
    new_username = st.text_input('Username', key='register_username')
    new_password = st.text_input('Password', type='password', key='register_password')
    privilege = st.selectbox('Privilege', ['admin', 'user'], key='register_privilege_select')

    if st.button('Register'):
        if register_user_from_admin(new_username, new_password, privilege):
            st.success(f"User {new_username} registered successfully with {privilege} privileges")
        else:
            st.error('Username already exists')

def manage_roles_page():
    st.markdown("<h2 style='text-align: center;'>Manage Roles</h2>", unsafe_allow_html=True)
    st.write("Promote users to admin or demote them to regular users.")

    user_data = get_user_data()

    if user_data.empty:
        st.write("No users found.")
    else:
        col1, col2 = st.columns(2)

        with col1:
            st.write("### Role Management")
            user_to_update = st.selectbox("Select a user to update", user_data.index, key="manage_roles_user_select")
            new_privilege = st.selectbox("Select new privilege", ["admin", "user"], key="manage_roles_privilege_select")

            if st.button("Update Privilege"):
                user_data.loc[user_to_update, 'privilege'] = new_privilege
                user_data.to_csv('users.csv')
                st.success(f"Updated {user_to_update}'s privilege to {new_privilege}")

        with col2:
            st.write("### User Data")
            user_data_no_password = user_data.drop(columns=['password'])
            st.markdown('<div class="larger-table">', unsafe_allow_html=True)
            st.dataframe(user_data_no_password)
            st.markdown('</div>', unsafe_allow_html=True)

if __name__ == '__main__':
    main()