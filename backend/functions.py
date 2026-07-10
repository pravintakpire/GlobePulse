import pandas as pd
import time
import numpy as np
from collections import defaultdict
from yahooquery import Ticker
import datetime
import os
from yahooquery import search
import json
import requests
import hashlib

def transform_date_sentiment(df):
    # Filter for only the overall_sentiment row
    overall_sentiment_df = df[df['Sentiment Topic'] == 'Overall sentiment']

    # Drop unnecessary columns
    overall_sentiment_df = overall_sentiment_df.drop(columns=['Sentiment Topic'])

    overall_sentiment_data = []
    for column in overall_sentiment_df.columns:
        value = overall_sentiment_df[column].iloc[0]
        if value == '':
            continue

        # Make value positive and multiply by 100
        value = abs(float(value)) * 100

        # Determine the color based on the original value
        color = 'rgba(0, 150, 136, 0.8)' if float(
            overall_sentiment_df[column].iloc[0]) >= 0 else 'rgba(255, 82, 82, 0.8)'

        # Convert date format to 'YYYY-MM-DD'
        date = pd.to_datetime(column, format='%m/%d/%Y').strftime('%Y-%m-%d')

        overall_sentiment_data.append({"time": date, "value": value, "color": color})

    # Sort the list of dictionaries by date
    overall_sentiment_data.sort(key=lambda x: datetime.datetime.strptime(x["time"], '%Y-%m-%d'))

    return overall_sentiment_data


def get_ticker(company_name):
    search_result = search(company_name)
    if 'quotes' in search_result and search_result['quotes']:
        return search_result['quotes'][0]['symbol']
    return None


def get_stock_history(tkr, period, interval):
    ticker = Ticker(tkr)

    df = ticker.history(period=period, interval=interval)

    # reset index
    df.reset_index(inplace=True)

    # Keep only columns 'date' and 'adjclose'
    df = df[['date', 'adjclose']]
    
    # Ensure the 'date' column is datetime-like
    df['date'] = pd.to_datetime(df['date'], errors='coerce', utc=True)
    
    # Convert to time zone naive (optional step based on your preference)
    df['date'] = df['date'].dt.tz_convert(None)
    
    # Format the 'date' column to "YYYY-MM-DD"
    df['date'] = df['date'].dt.strftime('%Y-%m-%d')

    # Convert to list of dictionaries
    price_series = [{"time": row['date'], "value": row['adjclose']} for _, row in df.iterrows()]

    return price_series


def aggregate_sentiment(sentiments: list):
    """
    Aggregates sentiment data across multiple dictionaries.

    For each topic, the function computes the median sentiment value across
    all input dictionaries, ignoring None values. If all values are None, the
    function returns (None, 0) for that topic. Otherwise, it returns a tuple
    with the median value rounded to two decimal places and the count of non-None
    entries for that topic.

    Parameters:
    ----------
    sentiments : list of dict
        A list of dictionaries where each dictionary represents sentiment
        data for different topics. The keys in each dictionary are topics,
        and the values are sentiment scores (between -1 and 1) or None.

    Returns:
    -------
    pandas.DataFrame
        A DataFrame where each row corresponds to a topic. The DataFrame has three columns:
        'sentiment topic' for the topic, 'value' for the median sentiment, and 'N' for the count
        of non-None entries.
    """
    topic_sentiments = defaultdict(list)

    # Collect the values for each topic
    for sentiment in sentiments:
        for topic, value in sentiment.items():
            topic_sentiments[topic].append(value)

    result = []

    # Compute the median for each topic or set to (None, 0) if all values are None
    for topic, values in topic_sentiments.items():
        non_none_values = [v for v in values if v is not None]
        if non_none_values:
            median_value = round(np.median(non_none_values), 2)
            weight = len(non_none_values)
            result.append({"Sentiment Topic": topic, "Sentiment Score": median_value, "N": weight})
        else:
            result.append({"Sentiment Topic": topic, "Sentiment Score": None, "N": 0})

    result_df = pd.DataFrame(result)

    # clean values in Sentiment Topic column
    result_df["Sentiment Topic"] = result_df["Sentiment Topic"].str.replace("_", " ").str.capitalize()

    # sort agg_df by N column in descending order
    result_df = result_df.sort_values('N', ascending=False)

    return result_df


def transform_sentiment(df: pd.DataFrame):
    """
    Transforms a dataframe of sentiment data into a wide format.

    The input dataframe should have two columns: 'date' and 'Sentiment'. The
    'Sentiment' column contains dictionaries mapping sentiment topics to their
    respective values. The function aggregates the sentiment values for each
    topic by date, ignoring None values, and calculates the average for each
    topic. The resulting dataframe has one column for each date and one row for
    each unique topic.

    Parameters:
    ----------
    df : pandas.DataFrame
        A dataframe with columns 'date' and 'Sentiment'. Each row contains a
        dictionary in 'Sentiment' column, mapping topics to sentiment scores
        or None.

    Returns:
    -------
    pandas.DataFrame
        A wide-format dataframe where the first column is 'sentiment topic'
        representing all unique topics, and subsequent columns are labeled by
        dates, containing the corresponding average sentiment values or None.
    """
    aggregated_data = defaultdict(lambda: defaultdict(list))

    for index, row in df.iterrows():
        for topic, sentiment in eval(row["sentiment"]).items():
            aggregated_data[row["date"]][topic].append(sentiment)

    aggregated_result = {}

    for date, topics in aggregated_data.items():
        result = {}
        for topic, values in topics.items():
            # Filter out None values
            non_none_values = [v for v in values if v is not None]
            if non_none_values:
                result[topic] = round(sum(non_none_values) / len(non_none_values), 2)
            else:
                result[topic] = None
        aggregated_result[date] = result

    # Step 2: Convert to wide format
    all_topics = set().union(*[d.keys() for d in aggregated_result.values()])
    wide_data = {'Sentiment Topic': list(all_topics)}

    for date, sentiments in aggregated_result.items():
        column_data = [sentiments.get(topic, None) for topic in all_topics]
        wide_data[date] = column_data

    wide_df = pd.DataFrame(wide_data)

    # Apply custom sorting
    wide_df = wide_df.sort_values('Sentiment Topic', key=lambda x: x.map(custom_sort_key))

    # sort columns by date except first column
    wide_df = wide_df[wide_df.columns[:1].tolist() + wide_df.columns[1:].sort_values().tolist()]

    # clean values in Sentiment Topic column
    wide_df["Sentiment Topic"] = wide_df["Sentiment Topic"].str.replace("_", " ").str.capitalize()

    return wide_df


def custom_sort_key(topic):
    return (0, '') if topic == 'overall_sentiment' else (1, topic)


def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
